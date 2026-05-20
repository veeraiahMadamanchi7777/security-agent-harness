package dev.securityharness.model;

import java.util.ArrayList;
import java.util.List;

public class ClassFact {
    public String packageName;
    public String className;
    public String file;
    public List<String> annotations = new ArrayList<>();
    public List<MethodFact> methods = new ArrayList<>();
}
