
rule k2321_039199aadba30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.039199aadba30912"
     cluster="k2321.039199aadba30912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi swisyn abzf"
     md5_hashes="['06a3648e1fd6a9697ed08ea6f70b443e','0f53eedc15e586455627396e90c57d55','835ecf6c5fe35be7389d4140203d49c9']"

   strings:
      $hex_string = { 58dd5e167140ce4e664db09291547dcccd7512f46ef95f0d9a5ada6aee210fef3349793dde2054a2b00dbb8d9cafd20c42245ca18f77dcf869e4ab55d09de3ec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
