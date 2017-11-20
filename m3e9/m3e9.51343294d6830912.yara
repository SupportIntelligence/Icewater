
rule m3e9_51343294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.51343294d6830912"
     cluster="m3e9.51343294d6830912"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['0bcca46edf88b67a0f5c702a3b17a312','15251cc98e17a14dcdf36ff2686e0f0c','ad8a0ccbb2f4f196c60debc8d97e1962']"

   strings:
      $hex_string = { 72de4034856a8f5109f284202cd482fbbde562655588799bd53937586cb03a0dce4cb57343a06fc3f0d763d9bc5bf3753cf73e98a86fe2b91c30f560cc9df1dc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
