#include "ctree_analyzer.h"

#include <ida/decompiler.hpp>
#include <ida/function.hpp>
#include <ida/name.hpp>

#include <format>

namespace codedump {

namespace {

namespace decomp = ida::decompiler;

std::string function_name_or_unknown(ida::Address ea) {
    ida::Result<std::string> name = ida::function::name_at(ea);
    if (name && !name->empty()) return *name;
    return "?";
}

} // namespace

// Visitor class for ctree traversal
class ProvCollector : public decomp::CtreeVisitor {
public:
    ProvCollector(CtreeAnalyzer *analyzer,
                  const std::vector<decomp::LocalVariable> &variables,
                  FunctionSummary &summary)
        : analyzer_(analyzer), variables_(variables), summary_(summary) {}

    decomp::VisitAction visit_expression(decomp::ExpressionView expr) override {
        switch (expr.type()) {
            case decomp::ItemType::ExprCall:
                process_call(expr);
                break;
            case decomp::ItemType::ExprAssign:
                process_assignment(expr);
                break;
            case decomp::ItemType::ExprObject:
                process_global_read(expr);
                break;
            default:
                break;
        }
        return decomp::VisitAction::Continue;
    }

private:
    void process_call(decomp::ExpressionView call_expr) {
        ida::Result<decomp::ExpressionView> callee = call_expr.call_callee();
        if (!callee) return;
        if (callee->type() != decomp::ItemType::ExprObject
            && callee->type() != decomp::ItemType::ExprHelper)
            return;

        ida::Address callee_ea = ida::BadAddress;
        std::string callee_name;
        if (callee->type() == decomp::ItemType::ExprObject) {
            ida::Result<ida::Address> object_address = callee->object_address();
            if (object_address)
                callee_ea = static_cast<ida::Address>(*object_address);
            callee_name = function_name_or_unknown(callee_ea);
        } else if (callee->type() == decomp::ItemType::ExprHelper) {
            ida::Result<std::string> helper = callee->helper_name();
            callee_name = helper ? *helper : "";
        }

        ida::Result<std::size_t> arg_count = call_expr.call_argument_count();
        if (!arg_count) return;

        for (size_t i = 0; i < *arg_count; i++) {
            ida::Result<decomp::ExpressionView> arg = call_expr.call_argument(i);
            if (!arg) continue;
            auto origin = analyzer_->normalize_expr(*arg, variables_);

            ArgUse au;
            au.call_ea = static_cast<ida::Address>(call_expr.address());
            au.callee_ea = callee_ea;
            au.arg_idx = (int)i;
            au.origin_kind = origin.kind;
            au.origin_id = origin.id;
            au.origin_name = origin.name;
            au.offset = origin.offset;
            au.length = origin.length;
            au.cast_txt = origin.cast_txt;
            au.mode = origin.mode;
            au.member_name = origin.member_name;
            au.callee_name = callee_name;
            au.confidence = origin.confidence;

            summary_.arg_uses.push_back(std::move(au));
        }
    }

    void process_assignment(decomp::ExpressionView asg_expr) {
        ida::Result<decomp::ExpressionView> lhs = asg_expr.left();
        ida::Result<decomp::ExpressionView> rhs = asg_expr.right();
        if (!lhs || !rhs) return;

        // Check if LHS is a local variable
        if (lhs->type() == decomp::ItemType::ExprVariable) {
            std::string var_name;
            int lhs_idx = -1;
            bool is_param = false;

            ida::Result<int> variable_index = lhs->variable_index();
            if (variable_index && *variable_index >= 0
                && static_cast<std::size_t>(*variable_index) < variables_.size()) {
                const auto &lv = variables_[static_cast<std::size_t>(*variable_index)];
                var_name = lv.name;
                lhs_idx = *variable_index;
                is_param = lv.is_argument;
            }

            // Handle function call return values specially
            if (rhs->type() == decomp::ItemType::ExprCall) {
                ida::Address callee_ea = ida::BadAddress;
                std::string callee_name;

                ida::Result<decomp::ExpressionView> callee = rhs->call_callee();
                if (callee && callee->type() == decomp::ItemType::ExprObject) {
                    ida::Result<ida::Address> object_address = callee->object_address();
                    if (object_address)
                        callee_ea = static_cast<ida::Address>(*object_address);
                    callee_name = function_name_or_unknown(callee_ea);
                } else if (callee && callee->type() == decomp::ItemType::ExprHelper) {
                    ida::Result<std::string> helper = callee->helper_name();
                    callee_name = helper ? *helper : "";
                }

                Alias alias;
                alias.lhs_kind = is_param ? BaseKind::Param : BaseKind::Local;
                alias.lhs_id = lhs_idx;
                alias.lhs_name = var_name;
                alias.rhs_kind = BaseKind::Return;
                alias.rhs_id = (int)(callee_ea & 0xFFFFFFFF);
                alias.rhs_name = callee_name;
                alias.offset = 0;
                alias.length = analyzer_->get_type_size(*rhs);
                alias.confidence = "high";

                summary_.aliases.push_back(std::move(alias));
            } else {
                auto rhs_origin = analyzer_->normalize_expr(*rhs, variables_);

                if (rhs_origin.kind != BaseKind::Unknown) {
                    Alias alias;
                    alias.lhs_kind = is_param ? BaseKind::Param : BaseKind::Local;
                    alias.lhs_id = lhs_idx;
                    alias.lhs_name = var_name;
                    alias.rhs_kind = rhs_origin.kind;
                    alias.rhs_name = rhs_origin.name;
                    alias.offset = rhs_origin.offset;
                    alias.length = rhs_origin.length;
                    alias.mode = rhs_origin.mode;
                    alias.member_name = rhs_origin.member_name;
                    alias.confidence = rhs_origin.confidence;

                    summary_.aliases.push_back(std::move(alias));
                }
            }
        }

        // Check if LHS is a global write
        if (lhs->type() == decomp::ItemType::ExprObject) {
            GlobalAccess ga;
            ida::Result<ida::Address> object_address = lhs->object_address();
            ga.global_ea = object_address ? static_cast<ida::Address>(*object_address) : ida::BadAddress;
            ida::Result<std::string> name = ida::name::get(ga.global_ea);
            ga.global_name = name ? *name : "";
            ga.is_write = true;
            ga.access_ea = static_cast<ida::Address>(asg_expr.address());
            summary_.global_accesses.push_back(std::move(ga));
        }
    }

    void process_global_read(decomp::ExpressionView obj_expr) {
        // Skip if this is the LHS of an assignment (handled in process_assignment)
        if (obj_expr.is_assignment_lhs())
            return;

        // Check if it's a global (not a function)
        ida::Result<ida::Address> object_address = obj_expr.object_address();
        if (!object_address) return;
        if (ida::function::at(*object_address))
            return;  // It's a function reference, not a global variable

        GlobalAccess ga;
        ga.global_ea = static_cast<ida::Address>(*object_address);
        ida::Result<std::string> name = ida::name::get(*object_address);
        ga.global_name = name ? *name : "";
        ga.is_write = false;
        ga.access_ea = static_cast<ida::Address>(obj_expr.address());
        summary_.global_accesses.push_back(std::move(ga));
    }

    CtreeAnalyzer *analyzer_;
    const std::vector<decomp::LocalVariable> &variables_;
    FunctionSummary &summary_;
};

bool CtreeAnalyzer::analyze_function(ida::Address func_ea, FunctionSummary &summary) {
    summary.func_ea = func_ea;
    summary.func_name = function_name_or_unknown(func_ea);

    // Decompile the function
    ida::Result<decomp::DecompiledFunction> decompiled =
        decomp::decompile(func_ea);
    if (!decompiled) {
        return false;
    }

    // Extract parameters and locals
    ida::Result<std::vector<decomp::LocalVariable>> variables =
        decompiled->variables();
    if (!variables) return false;

    for (const auto &lv : *variables) {
        if (lv.is_argument) {
            summary.params.push_back(lv.name);
        } else {
            summary.locals.push_back(lv.name);
        }
    }

    // Visit the ctree
    ProvCollector collector(this, *variables, summary);
    decomp::VisitOptions options;
    options.track_parents = true;
    ida::Result<int> visited = decompiled->visit(collector, options);
    if (!visited) return false;

    return true;
}

CtreeAnalyzer::ExprOrigin CtreeAnalyzer::normalize_expr(
    decomp::ExpressionView expr,
    const std::vector<decomp::LocalVariable> &variables) {
    ExprOrigin result;

    // Handle casts - unwrap and record
    while (expr.type() == decomp::ItemType::ExprCast) {
        ida::Result<std::string> type = expr.type_declaration();
        if (type) result.cast_txt = *type;
        ida::Result<decomp::ExpressionView> inner = expr.left();
        if (!inner) return result;
        expr = *inner;
    }

    switch (expr.type()) {
        case decomp::ItemType::ExprVariable: {
            // Local variable or parameter
            ida::Result<int> variable_index = expr.variable_index();
            if (variable_index && *variable_index >= 0
                && static_cast<std::size_t>(*variable_index) < variables.size()) {
                const auto &lv = variables[static_cast<std::size_t>(*variable_index)];
                result.kind = lv.is_argument ? BaseKind::Param : BaseKind::Local;
                result.id = lv.name;
                result.name = lv.name;
                result.length = lv.width;
                result.confidence = "high";
            }
            break;
        }

        case decomp::ItemType::ExprObject: {
            // Global variable or function
            result.kind = BaseKind::Global;
            ida::Result<ida::Address> object_address = expr.object_address();
            ida::Address ea = object_address ? static_cast<ida::Address>(*object_address) : ida::BadAddress;
            ida::Result<std::string> name = ida::name::get(ea);
            result.id = std::format("0x{:X}", ea);
            result.name = name ? *name : "";
            result.confidence = "high";
            break;
        }

        case decomp::ItemType::ExprNumber: {
            // Constant
            result.kind = BaseKind::Constant;
            ida::Result<std::uint64_t> value = expr.number_value();
            result.id = std::format("0x{:x}", value ? *value : 0);
            result.name = result.id;
            result.confidence = "high";
            break;
        }

        case decomp::ItemType::ExprString: {
            // String constant
            result.kind = BaseKind::Constant;
            result.id = "str";
            result.name = "(string)";
            result.confidence = "high";
            break;
        }

        case decomp::ItemType::ExprFloatNumber: {
            // Floating point constant
            result.kind = BaseKind::Constant;
            result.id = "fnum";
            result.name = "(float)";
            result.confidence = "high";
            break;
        }

        case decomp::ItemType::ExprSizeof: {
            // sizeof operator - always constant
            result.kind = BaseKind::Constant;
            result.id = "sizeof";
            result.name = "sizeof()";
            result.confidence = "high";
            break;
        }

        case decomp::ItemType::ExprRef: {
            // Address-of operator
            ida::Result<decomp::ExpressionView> left = expr.left();
            if (!left) break;
            auto inner = normalize_expr(*left, variables);
            result = inner;
            result.mode = "&";
            break;
        }

        case decomp::ItemType::ExprDeref: {
            // Dereference
            ida::Result<decomp::ExpressionView> left = expr.left();
            if (!left) break;
            auto inner = normalize_expr(*left, variables);
            result = inner;
            result.mode = "*";
            break;
        }

        case decomp::ItemType::ExprIndex: {
            // Array indexing
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto base = normalize_expr(*x, variables);
            result = base;

            // Calculate offset from index
            if (y->type() == decomp::ItemType::ExprNumber) {
                int elem_size = 1;
                ida::Result<int> pointed_size = x->pointed_type_byte_width();
                if (pointed_size) elem_size = *pointed_size;
                ida::Result<std::uint64_t> value = y->number_value();
                result.offset += (int)((value ? *value : 0) * elem_size);
            } else {
                // Non-constant index - lower confidence
                result.confidence = "low";
            }
            break;
        }

        case decomp::ItemType::ExprMemberPtr:
        case decomp::ItemType::ExprMemberRef: {
            // Structure member access
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto base = normalize_expr(*x, variables);
            result = base;
            ida::Result<std::uint32_t> offset = expr.member_offset();
            if (offset) result.offset += static_cast<int>(*offset);

            // Try to resolve member name
            ida::Result<std::string> member = expr.member_name();
            if (member) result.member_name = *member;
            break;
        }

        case decomp::ItemType::ExprAdd: {
            // Addition (often used for pointer arithmetic)
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            if (left.kind != BaseKind::Unknown) {
                result = left;
                if (y->type() == decomp::ItemType::ExprNumber) {
                    ida::Result<std::uint64_t> value = y->number_value();
                    result.offset += (int)(value ? *value : 0);
                } else {
                    // Non-constant addend
                    auto right = normalize_expr(*y, variables);
                    if (right.kind != BaseKind::Unknown && right.kind != BaseKind::Constant) {
                        result.kind = BaseKind::Derived;
                        result.confidence = "low";
                    }
                }
            } else {
                auto right = normalize_expr(*y, variables);
                result = right;
                if (x->type() == decomp::ItemType::ExprNumber) {
                    ida::Result<std::uint64_t> value = x->number_value();
                    result.offset += (int)(value ? *value : 0);
                }
            }
            break;
        }

        case decomp::ItemType::ExprSub: {
            // Subtraction
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            if (left.kind != BaseKind::Unknown) {
                result = left;
                if (y->type() == decomp::ItemType::ExprNumber) {
                    ida::Result<std::uint64_t> value = y->number_value();
                    result.offset -= (int)(value ? *value : 0);
                } else {
                    result.confidence = "low";
                }
            }
            break;
        }

        case decomp::ItemType::ExprMul: {
            // Multiplication (stride calculation for arrays)
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            auto right = normalize_expr(*y, variables);
            if (y->type() == decomp::ItemType::ExprNumber && left.kind != BaseKind::Unknown) {
                result = left;
                ida::Result<std::uint64_t> value = y->number_value();
                result.offset *= (int)(value ? *value : 0);
            } else if (x->type() == decomp::ItemType::ExprNumber && right.kind != BaseKind::Unknown) {
                result = right;
                ida::Result<std::uint64_t> value = x->number_value();
                result.offset *= (int)(value ? *value : 0);
            } else if (left.kind != BaseKind::Unknown) {
                result = left;
                result.confidence = "low";
            }
            break;
        }

        case decomp::ItemType::ExprDivSigned:
        case decomp::ItemType::ExprDivUnsigned: {
            // Division - taint flows through from numerator
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto left = normalize_expr(*x, variables);
            result = left;
            result.confidence = "low";
            break;
        }

        case decomp::ItemType::ExprModSigned:
        case decomp::ItemType::ExprModUnsigned: {
            // Modulo - taint flows through
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto left = normalize_expr(*x, variables);
            result = left;
            result.confidence = "low";
            break;
        }

        case decomp::ItemType::ExprShiftLeft: {
            // Left shift
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto base = normalize_expr(*x, variables);
            result = base;
            if (y->type() == decomp::ItemType::ExprNumber) {
                ida::Result<std::uint64_t> value = y->number_value();
                result.offset <<= (int)(value ? *value : 0);
            }
            break;
        }

        case decomp::ItemType::ExprShiftRightSigned:
        case decomp::ItemType::ExprShiftRightUnsigned: {
            // Right shift (signed/unsigned)
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto base = normalize_expr(*x, variables);
            result = base;
            if (y->type() == decomp::ItemType::ExprNumber) {
                ida::Result<std::uint64_t> value = y->number_value();
                result.offset >>= (int)(value ? *value : 0);
            }
            break;
        }

        case decomp::ItemType::ExprBitAnd: {
            // Bitwise AND - taint flows through, often used for masking
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            auto right = normalize_expr(*y, variables);
            // Prefer the non-constant operand
            if (left.kind != BaseKind::Unknown && left.kind != BaseKind::Constant) {
                result = left;
            } else if (right.kind != BaseKind::Unknown && right.kind != BaseKind::Constant) {
                result = right;
            } else {
                result = left;
            }
            break;
        }

        case decomp::ItemType::ExprBitOr: {
            // Bitwise OR - both operands contribute
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            auto right = normalize_expr(*y, variables);
            if (left.kind != BaseKind::Unknown && left.kind != BaseKind::Constant) {
                result = left;
                if (right.kind != BaseKind::Unknown && right.kind != BaseKind::Constant) {
                    result.kind = BaseKind::Derived;
                    result.confidence = "low";
                }
            } else {
                result = right;
            }
            break;
        }

        case decomp::ItemType::ExprXor: {
            // Bitwise XOR - taint flows through
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            auto right = normalize_expr(*y, variables);
            if (left.kind != BaseKind::Unknown && left.kind != BaseKind::Constant) {
                result = left;
            } else {
                result = right;
            }
            break;
        }

        case decomp::ItemType::ExprBitNot: {
            // Bitwise NOT - taint flows through
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto inner = normalize_expr(*x, variables);
            result = inner;
            break;
        }

        case decomp::ItemType::ExprNeg: {
            // Negation - taint flows through
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto inner = normalize_expr(*x, variables);
            result = inner;
            if (result.offset != 0) {
                result.offset = -result.offset;
            }
            break;
        }

        case decomp::ItemType::ExprLogicalNot: {
            // Logical NOT - result is boolean but tainted by operand
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto inner = normalize_expr(*x, variables);
            result = inner;
            result.confidence = "low";
            break;
        }

        case decomp::ItemType::ExprTernary: {
            // Ternary operator: cond ? true_expr : false_expr
            ida::Result<decomp::ExpressionView> y = expr.right();
            ida::Result<decomp::ExpressionView> z = expr.third();
            if (!y || !z) break;
            auto true_val = normalize_expr(*y, variables);
            auto false_val = normalize_expr(*z, variables);

            // Prefer the branch with known origin
            if (true_val.kind != BaseKind::Unknown) {
                result = true_val;
            } else {
                result = false_val;
            }
            // Conditional merge always has low confidence
            result.confidence = "low";
            break;
        }

        case decomp::ItemType::ExprLogicalOr:
        case decomp::ItemType::ExprLogicalAnd: {
            // Logical OR/AND - result depends on both operands
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            auto right = normalize_expr(*y, variables);
            if (left.kind != BaseKind::Unknown) {
                result = left;
            } else {
                result = right;
            }
            result.confidence = "low";
            break;
        }

        // Comparison operators - taint flows through for data dependency
        case decomp::ItemType::ExprEqual:
        case decomp::ItemType::ExprNotEqual:
        case decomp::ItemType::ExprSignedLT:
        case decomp::ItemType::ExprSignedLE:
        case decomp::ItemType::ExprSignedGT:
        case decomp::ItemType::ExprSignedGE:
        case decomp::ItemType::ExprUnsignedLT:
        case decomp::ItemType::ExprUnsignedLE:
        case decomp::ItemType::ExprUnsignedGT:
        case decomp::ItemType::ExprUnsignedGE: {
            // Track the first non-constant operand
            ida::Result<decomp::ExpressionView> x = expr.left();
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (!x || !y) break;
            auto left = normalize_expr(*x, variables);
            auto right = normalize_expr(*y, variables);
            if (left.kind != BaseKind::Unknown && left.kind != BaseKind::Constant) {
                result = left;
            } else if (right.kind != BaseKind::Unknown && right.kind != BaseKind::Constant) {
                result = right;
            }
            result.confidence = "low";
            break;
        }

        case decomp::ItemType::ExprComma: {
            // Comma operator - result is the right operand
            ida::Result<decomp::ExpressionView> y = expr.right();
            if (y) result = normalize_expr(*y, variables);
            break;
        }

        case decomp::ItemType::ExprCall: {
            // Function call - result is return value
            ida::Address callee_ea = ida::BadAddress;
            std::string callee_name;

            ida::Result<decomp::ExpressionView> callee = expr.call_callee();
            if (callee && callee->type() == decomp::ItemType::ExprObject) {
                ida::Result<ida::Address> object_address = callee->object_address();
                if (object_address) callee_ea = static_cast<ida::Address>(*object_address);
                callee_name = function_name_or_unknown(callee_ea);
            } else if (callee && callee->type() == decomp::ItemType::ExprHelper) {
                ida::Result<std::string> helper = callee->helper_name();
                callee_name = helper ? *helper : "";
            }

            result.kind = BaseKind::Return;
            result.id = std::format("0x{:X}", callee_ea);
            result.name = callee_name;
            result.confidence = "med";
            break;
        }

        case decomp::ItemType::ExprPreInc:
        case decomp::ItemType::ExprPreDec:
        case decomp::ItemType::ExprPostInc:
        case decomp::ItemType::ExprPostDec: {
            // Pre/post increment/decrement - taint flows through
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (!x) break;
            auto inner = normalize_expr(*x, variables);
            result = inner;
            break;
        }

        // Compound assignments - LHS is both source and destination
        case decomp::ItemType::ExprAssignAdd:
        case decomp::ItemType::ExprAssignSub:
        case decomp::ItemType::ExprAssignMul:
        case decomp::ItemType::ExprAssignShiftRightSigned:
        case decomp::ItemType::ExprAssignShiftRightUnsigned:
        case decomp::ItemType::ExprAssignShiftLeft:
        case decomp::ItemType::ExprAssignDivSigned:
        case decomp::ItemType::ExprAssignDivUnsigned:
        case decomp::ItemType::ExprAssignModSigned:
        case decomp::ItemType::ExprAssignModUnsigned:
        case decomp::ItemType::ExprAssignBitAnd:
        case decomp::ItemType::ExprAssignBitOr:
        case decomp::ItemType::ExprAssignXor: {
            // For compound assignment x op= y, the result flows from x
            ida::Result<decomp::ExpressionView> x = expr.left();
            if (x) result = normalize_expr(*x, variables);
            break;
        }

        default:
            // Unknown expression type
            break;
    }

    return result;
}

int CtreeAnalyzer::get_type_size(decomp::ExpressionView expr) {
    ida::Result<int> size = expr.type_byte_width();
    return size ? *size : 0;
}

AliasChain CtreeAnalyzer::resolve_alias_chain(
    const std::string &var_name,
    const std::vector<Alias> &aliases,
    int max_depth
) {
    AliasChain result;
    result.accumulated_offset = 0;

    // Build a map from variable name to its definition
    std::map<std::string, const Alias*> alias_map;
    for (const auto &alias : aliases) {
        // Only track local/param LHS assignments
        if (alias.lhs_kind == BaseKind::Local || alias.lhs_kind == BaseKind::Param) {
            alias_map[alias.lhs_name] = &alias;
        }
    }

    std::set<std::string> visited;
    std::string current = var_name;
    int depth = 0;

    while (depth < max_depth && visited.find(current) == visited.end()) {
        visited.insert(current);
        result.intermediate_vars.push_back(current);

        auto it = alias_map.find(current);
        if (it == alias_map.end()) {
            // No more aliases - this is the ultimate origin
            result.ultimate_origin = current;
            break;
        }

        const Alias &alias = *it->second;
        result.accumulated_offset += alias.offset;
        result.offset_deltas.push_back(alias.offset);

        // Determine confidence based on chain
        if (alias.confidence == "low") {
            result.confidence = "low";
        } else if (alias.confidence == "med" && result.confidence == "high") {
            result.confidence = "med";
        }

        // Check if RHS is another local/param that we can continue tracing
        if (alias.rhs_kind == BaseKind::Local || alias.rhs_kind == BaseKind::Param) {
            current = alias.rhs_name;
        } else {
            // Reached a non-local origin (global, constant, return value)
            result.ultimate_origin = alias.rhs_name;
            result.origin_kind = alias.rhs_kind;
            break;
        }

        depth++;
    }

    // If we exhausted depth or hit a cycle, mark as low confidence
    if (depth >= max_depth || (visited.find(current) != visited.end() && result.ultimate_origin.empty())) {
        result.confidence = "low";
        if (result.ultimate_origin.empty()) {
            result.ultimate_origin = current;
        }
    }

    return result;
}

} // namespace codedump
