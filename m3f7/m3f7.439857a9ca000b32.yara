
rule m3f7_439857a9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.439857a9ca000b32"
     cluster="m3f7.439857a9ca000b32"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker autolike script"
     md5_hashes="['278494882268e836fb6695d0454eb3ae','40059120d4bf4f714e91df650ad436d7','a13343391dd5a07445505d06491ac322']"

   strings:
      $hex_string = { 42794964282248544d4c322229293b27207461726765743d27636f6e66696748544d4c3227207469746c653d274368e1bb896e682073e1bbad61273e0a3c696d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
