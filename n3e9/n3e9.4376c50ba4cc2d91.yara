
rule n3e9_4376c50ba4cc2d91
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4376c50ba4cc2d91"
     cluster="n3e9.4376c50ba4cc2d91"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['18b773c15c0079683e112f33085b60db','2d583b2ac552352af5aacb9eea8004fb','fac8daf9feffcfe93d2d93512e7d2349']"

   strings:
      $hex_string = { 1569bc97ba66a0c135746513566a7924a58f4ccc946b9c7eac82aecd9dafe87a2ec9442ddb1812dc9575e028e3260ddae9223c16f42c0e256cc4f852375a1f27 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
