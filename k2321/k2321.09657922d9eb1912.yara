
rule k2321_09657922d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09657922d9eb1912"
     cluster="k2321.09657922d9eb1912"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['093458307346fe898bf807ee8872ea1c','3b6318badc03d410dcfc57f2679b5b05','df275826f2e22e0f573d04294634416d']"

   strings:
      $hex_string = { 5ab5620c674885328871b336c6021a237ac8bc6bdeaef6278a7255d502dbefd9260bf64a49ad15c4c2a6252b43fffbf1894d81fef7e5f9a413dd68a8f0e4c5aa }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
