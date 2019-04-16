#!/usr/bin/python2
# Mohammad Riftadi <m.riftadi@student.tudelft.nl>

import argparse
import future
import os
import pprint
import time

from jinja2 import Environment, FileSystemLoader

PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_ENVIRONMENT = Environment(
    autoescape=False,
    loader=FileSystemLoader(os.path.join(PATH, 'templates')),
    trim_blocks=False)

DDPATH = "functions/ddos_detector/ddos_detector."
HHPATH = "functions/heavy_hitter/heavy_hitter."
SSPATH = "functions/ss_detector/ss_detector."

def render_template(template_filename, context = None):
    if not context:
        context = {}
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)


class P4CodeGenerator(object):
    def __init__(self, filename = None):
        self.filename = filename
        self.lines = None
        self.intents = None
        self.load_file()

    def load_file(self):
        assert self.filename
        with open(self.filename) as f:
            lines = f.readlines()
        self.lines = [line.strip('\n') for line in lines]
        # give one line padding to make reading the last intent easier
        self.lines.append("")

    def print_intents(self):
        pprint.pprint(self.intents)

    def process_intents(self):
        assert self.lines

        tmp_intents = self.split_lines_by_intent()
        self.intents = self.parse_intent_lines(tmp_intents)

    def split_lines_by_intent(self):
        tmp_intents = []
        inside_intent_flag = False

        for line in self.lines:
            if inside_intent_flag:
                if line and line != '\r':
                    new_intent.append(line)
                else:
                    tmp_intents.append(new_intent)
                    inside_intent_flag = False
            else:  # not inside intent
                if "define intent" in line:
                    inside_intent_flag = True
                    new_intent = []
                    new_intent.append(line)

        return tmp_intents

    def parse_intent_lines(self, tmp_intents):
        outputs = []

        for lines in tmp_intents:
            new_intent = {}
            _, _, name = lines[0].split()
            new_intent["name"] = name.strip(':')

            for line in lines[1:]:
                key, value = line.split()
                if "threshold" in value:
                    op, num = value.replace(')', '(').split('(')[1].split(',')
                    value = {"thres" : {"op" : op.strip('\''), "val" : int(num)}}
                elif "traffic" in value:
                    protocols = value.replace(')', '(').split('(')[1].split(',')
                    value = [protocol.strip('\'') for protocol in protocols]

                new_intent[key] = value

            outputs.append(new_intent)

        return outputs

    def get_intent_actions(self):
        return list(set([intent["apply"] for intent in self.intents]))

    def get_const_def_text(self):
        lines = []
        for intent in self.intents:
            # refactor this
            if "drop_ddos" in intent["apply"]:
                ddos_threshold_val = intent["with"]["thres"]["val"]
                template_name = DDPATH + "const.jinja2"
                context = {"ddos_threshold_val": ddos_threshold_val}
                lines.append(render_template(template_name, context))
            elif "drop_heavy_hitters" in intent["apply"]:
                hh_threshold_val = intent["with"]["thres"]["val"]
                template_name = HHPATH + "const.jinja2"
                context = {"hh_threshold_val": hh_threshold_val}
                lines.append(render_template(template_name, context))
            elif "drop_superspreader" in intent["apply"]:
                ss_threshold_val = intent["with"]["thres"]["val"]
                template_name = SSPATH + "const.jinja2"
                context = {"ss_threshold_val": ss_threshold_val}
                lines.append(render_template(template_name, context))
        return "\n".join(lines)

    def get_metadata_text(self):
        lines = []
        for intent in self.intents:
            # refactor this
            if "drop_ddos" in intent["apply"]:
                template_name = DDPATH + "metadata.jinja2"
                lines.append(render_template(template_name))
            elif "drop_heavy_hitters" in intent["apply"]:
                template_name = HHPATH + "metadata.jinja2"
                lines.append(render_template(template_name))
            elif "drop_superspreader" in intent["apply"]:
                template_name = SSPATH + "metadata.jinja2"
                lines.append(render_template(template_name))
        return "\n".join(lines)

    def get_dummy_text(self):
        lines = []
        for intent in self.intents:
            # refactor this
            if "drop_ddos" in intent["apply"]:
                template_name = DDPATH + "dummy.jinja2"
                lines.append(render_template(template_name))
            elif "drop_heavy_hitters" in intent["apply"]:
                template_name = HHPATH + "dummy.jinja2"
                lines.append(render_template(template_name))
            elif "drop_superspreader" in intent["apply"]:
                template_name = SSPATH + "dummy.jinja2"
                lines.append(render_template(template_name))
        return "\n".join(lines)

    def get_functions_text(self):
        lines = []
        for intent in self.intents:
            # refactor this
            if "drop_ddos" in intent["apply"]:
                template_name = DDPATH + "func.jinja2"
                lines.append(render_template(template_name))
            elif "drop_heavy_hitters" in intent["apply"]:
                template_name = HHPATH + "func.jinja2"
                lines.append(render_template(template_name))
            elif "drop_superspreader" in intent["apply"]:
                template_name = SSPATH + "func.jinja2"
                lines.append(render_template(template_name))
        return "\n\n".join(lines)

    def get_pre_apply_text(self):
        lines = []
        for intent in self.intents:
            # refactor this
            if "drop_ddos" in intent["apply"]:
                template_name = DDPATH + "pre_apply.jinja2"
                lines.append(render_template(template_name))
            elif "drop_heavy_hitters" in intent["apply"]:
                template_name = HHPATH + "pre_apply.jinja2"
                lines.append(render_template(template_name))
            elif "drop_superspreader" in intent["apply"]:
                template_name = SSPATH + "pre_apply.jinja2"
                lines.append(render_template(template_name))
        return "\n".join(lines)

    def get_post_apply_text(self):
        lines = []
        for intent in self.intents:
            # refactor this
            if "drop_ddos" in intent["apply"]:
                template_name = DDPATH + "post_apply.jinja2"
                lines.append(render_template(template_name))
            elif "drop_heavy_hitters" in intent["apply"]:
                template_name = HHPATH + "post_apply.jinja2"
                lines.append(render_template(template_name))
            elif "drop_superspreader" in intent["apply"]:
                template_name = SSPATH + "post_apply.jinja2"
                lines.append(render_template(template_name))

        return (" else ".join(lines) + " else {\n                "
                    "forward_port.apply();\n            }")

    def generate_p4code(self, output_fname):
        intent_actions = self.get_intent_actions()

        context = None
        if len(intent_actions) > 0:
            const_def_text = self.get_const_def_text()
            metadata_text = self.get_metadata_text()
            dummy_text = self.get_dummy_text()
            functions_text = self.get_functions_text()
            pre_apply_text = self.get_pre_apply_text()
            post_apply_text = self.get_post_apply_text()

            context = {
                "const_def_text" : const_def_text,
                "metadata_text" : metadata_text,
                "dummy_text" : dummy_text,
                "functions_text" : functions_text,
                "pre_apply_text" : pre_apply_text,
                "post_apply_text" : post_apply_text,
            }

        template_name = "basic.p4.jinja2"
        result = render_template(template_name, context)
        with open(output_fname, 'w') as handler:
            handler.write(result)


def read_args():
    parser = argparse.ArgumentParser(
                description = 'Generate P4 code from intents.')
    parser.add_argument("intent_filename", default = "intent.txt",
                nargs='?', help = "a text file containing intents")
    return parser.parse_args()


def main(args):
    intent_fname = args.intent_filename
    # p4code_fname = "evaluate.p4"
    p4code_fname = "s1_running.p4"
    sum = 0.0
    times = 0 + 1

    for i in range(times):
        start = time.time()
        # print("Reading intents from {}.".format(intent_fname))
        gen = P4CodeGenerator(intent_fname)
        # print("Parsing intents.")
        gen.process_intents()
        # print("Outputing p4 code to {}.".format(p4code_fname))
        gen.generate_p4code(p4code_fname)
        end = time.time()
        delta = (end - start)*1000
        print(delta)
        if i > 0:
            sum += delta

    # print("Average: %f" % (sum/(times-1)))
    print("Done! Exiting..")


if __name__ == "__main__":
    args = read_args()
    main(args)
