
rule o26bb_51bbd4c2c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.51bbd4c2c4000b32"
     cluster="o26bb.51bbd4c2c4000b32"
     cluster_size="471"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury ursu heuristic"
     md5_hashes="['9039dd03a214620383ae818cd885a37031c809ad','fdd839f749e12c6fc1bbdaabeab04790d376ac40','c9fbcce9b10ec2537a8a7bf3e159a45a52052472']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.51bbd4c2c4000b32"

   strings:
      $hex_string = { f083c41885f67520beffffff7feb198b550c33c985f674108b7d080fb604116689044f413bce72f352e82a420000595f8bc65e5b5dc3558bec518d45fc506a01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
