package dev.securityharness.model;

import java.util.ArrayList;
import java.util.List;

public class MethodFact {
    public String methodName;
    public int line;
    public List<String> annotations = new ArrayList<>();
    public List<String> parameters = new ArrayList<>();
    public List<String> methodCalls = new ArrayList<>();
}
