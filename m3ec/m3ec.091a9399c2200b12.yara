
rule m3ec_091a9399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.091a9399c2200b12"
     cluster="m3ec.091a9399c2200b12"
     cluster_size="18"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gozi zusy hijacker"
     md5_hashes="['00b183dab57be4bbe0b3882b57285c41','00db5dfbaf6508a3837d34891072263f','a3f2794af64e9719365fb07ef2ad2fb2']"

   strings:
      $hex_string = { 3dde25cbbea847d535b44e31da8d74622ceb9e59d171139fd781e36f9541f0a4b89cd4ca06486872e6bb80acc684abb6365a82fb077a1079f6b3700453880b7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
