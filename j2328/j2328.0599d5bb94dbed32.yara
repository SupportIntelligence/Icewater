
rule j2328_0599d5bb94dbed32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2328.0599d5bb94dbed32"
     cluster="j2328.0599d5bb94dbed32"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit html"
     md5_hashes="['36ee0a83c78af02e7f733aba67e27e9db428bbb5','560a7906e3779c0aa58d637ecaa127ffb23d0b97','6903f1fa750030955335d40a060d4bf95459b14e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2328.0599d5bb94dbed32"

   strings:
      $hex_string = { 6465736372697074696f6e3e3c215b43444154415b323031382d30332d32392020e5b9bce7a89ae59c92e88889e8bea6e6ad8ce594b1e6af94e8b3bdefbc8ce9 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
