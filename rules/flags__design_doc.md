# Design Document

Source: https://rules.ectf.mitre.org/2026/flags/design_doc.html

# Design Document[¶](#design-document "Permalink to this heading")

## Overview[¶](#overview "Permalink to this heading")

The design document is a **technical document** to convey the design of your
project. Generally, you need to show that your design will meet the
[Functional Requirements](../../glossary.html#term-Functional-Requirements) and the [Security Requirements](../../glossary.html#term-Security-Requirements).

As this is a competition focusing on security and embedded systems, you should
be describing all of the security measures your design takes, such as each of
your:

* Cryptographic algorithms
* Cryptographic secrets
* Protocols
* Serialization formats or other important data structures
* Countermeasures
* Other security considerations

And, you want to answer:

* How does your design fulfill the requirements?
* What does a human need to do to handle your project?
* How are your choices suitable for the design and target platform?
* How does your design protect against attacks specific to embedded devices?

There are two places this design document can earn you points.

1. [Design Phase Flag](design_flags.html): This is worth 100 points.
   For full points, it needs to be submitted by
   [January 31st](../schedule/index.html#important-dates), but it does not need to be your
   final submission. It’s okay for this submission to just be a draft. You can
   submit this by posting your document to the testing api as detailed in [Submitting a Design Doc](../handoff/testing_service.html#submit-design-doc).

Note

It’s okay to submit a draft for this initial design document, and you may
resubmit as many times you would like until [handoff](../../glossary.html#term-Handoff), however you also
need to show that you are making progress on your design and you can’t just
send us nonsense.

2. [Documentation Points](documentation_points.html): The amount of
   points this is worth is a percentage of the highest uncaptured attack flag by
   the end of the [attack phase](../../glossary.html#term-Attack-Phase). This version of the document should be
   the final version and you will include it in your final submission. The
   percentage your team gets is based on how we grade the quality of your code
   and your design document.

## Scoring[¶](#scoring "Permalink to this heading")

The quality of the **final** design document (along with your code quality) will
determine the amount of points you get for it. These points are only applied
to the documentation points, and *not* the design phase flag.

|  |  |
| --- | --- |
| **~100%** | Very clear, thought out, and easy to understand. Amazing documentation, comments, and code quality. |
| **~75%** | Your comments are good, the documentation is good, and your code is readable. |
| **~50%** | Suitable as a draft. Documentation might be a little unclear needlessly long, possibly missing important parts, or a bit of code might be poorly formatted. |
| **~25%** | The code is confusing, and there is little documentation. |
| **~0%** | You didn’t submit anything, your code and documentation is highly confusing, or you didn’t submit your source, or your final submission is obfuscated. |

Again, this is a technical document that you are creating. It needs to be
suitable as a reference for someone to read and look things up.

## Advice[¶](#advice "Permalink to this heading")

* Start small, and add only when you’ve finished everything before.
* A simpler design can be a more secure design.
* Include what the reader would probably care about, and the structure of
  your document should help the reader find what they’re looking for.

  + Does putting in more information help the reader find what they want?
* You don’t need to stick with the same design after submitting the design phase
  flag. That was a draft, and you only need to worry about the document being
  high quality for [handoff](../../glossary.html#term-Handoff).
* Keep your wording concise. A longer paper does not mean a higher score.
* Keep your document structure consistent. If other parts of the document follow
  a similar structure to one part, it can be easier for a reader to find what
  they are looking for.

