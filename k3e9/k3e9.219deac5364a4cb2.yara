
rule k3e9_219deac5364a4cb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.219deac5364a4cb2"
     cluster="k3e9.219deac5364a4cb2"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['571a3a9b141be9a29254fa9ecfacfef0','7410a79d7a7d2f5c7d3048846ad0d7bc','e6b84e1062c36c7cf52bb9aab77c50d6']"

   strings:
      $hex_string = { d4930444149e277377de0e9a3fc17ce5299b350b988dc76cacff488b948f3768f7cc01e1453f49c6a5c3d3a2fe153d99dc7a6134e66aa9edf41874f0ad2dfdcd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
