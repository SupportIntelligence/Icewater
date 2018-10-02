
rule n26bb_4918bcc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4918bcc1c8000b12"
     cluster="n26bb.4918bcc1c8000b12"
     cluster_size="87"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaik click malicious"
     md5_hashes="['f1891a756a1cacec7a42f5ef9807769967817402','764565716e922210fb6fa3b8c9138aaa44df5da2','88efaf622075a87bb9d45b5a0c50a621640f09d9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4918bcc1c8000b12"

   strings:
      $hex_string = { 6e636f64696e6746696c746572466163746f72790018a628ea07000016475549445f435553544f4d5f434f4e4649524d4f424a45435453414645545900183329 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
