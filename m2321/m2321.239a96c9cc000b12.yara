
rule m2321_239a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.239a96c9cc000b12"
     cluster="m2321.239a96c9cc000b12"
     cluster_size="17"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['06d16514476b8e55ab880543ab8aec7b','1c6a111ccea9aa3c35e534e25fedfafa','c7b216dcaecd6b29d2bdaf74fd9a66df']"

   strings:
      $hex_string = { b6270d9623d09387305265aee32ac5c6f8bbacc47a5e464357dd742b1dcaa653bdba8848253c017089b5e5860316732e11a7ec342e4c859d5aef4b5532503aa0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
