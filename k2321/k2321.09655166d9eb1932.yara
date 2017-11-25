
rule k2321_09655166d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09655166d9eb1932"
     cluster="k2321.09655166d9eb1932"
     cluster_size="3"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['4d241c82d47e6bbf57dec1e44f7cfc6c','632f20c01b346873fc3d6e1e4c181ffb','8ec53e2f13024059b1e5c34c83b0ea91']"

   strings:
      $hex_string = { 973a0a96f290b961f740fa38acf21ced33b4ba2182cbd50b7f51ea4e919e55722ae0327edd8e5c2822239750ee6b00a3d25e793cc067ab9deb99adec477705d8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
