
rule k2321_29251163d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29251163d9eb1912"
     cluster="k2321.29251163d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt symmi"
     md5_hashes="['6d148b8b708e6610c1e840c13f25cde5','80105799f70939f2e05cd87bb9e62604','f239a59f77cc8b8432fbfea317a33b8f']"

   strings:
      $hex_string = { 17a1e3185e7b46411bd4c53ea04dd10b6b6c84dba5c3f682c930ac5d15e1032acd00a6794aadc741e012d7e40d29545a92779e67c4766c07bb323d21b63513ec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
