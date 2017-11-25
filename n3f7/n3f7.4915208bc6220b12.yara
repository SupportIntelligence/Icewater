
rule n3f7_4915208bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.4915208bc6220b12"
     cluster="n3f7.4915208bc6220b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['42901cf8fe72231edf2786ae0b0c7569','4e6a1279180b446e223da63cede1e3d9','f563aa420751e8dcf77c1f908b52825c']"

   strings:
      $hex_string = { 3a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f5265 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
