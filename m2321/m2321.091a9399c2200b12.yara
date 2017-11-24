
rule m2321_091a9399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.091a9399c2200b12"
     cluster="m2321.091a9399c2200b12"
     cluster_size="153"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gozi zusy hijacker"
     md5_hashes="['00db5dfbaf6508a3837d34891072263f','01fce2c1eef86f76adaf3d1fd9872b4f','1e9a0fb338a828b72dfc36cccfd5f44c']"

   strings:
      $hex_string = { 3dde25cbbea847d535b44e31da8d74622ceb9e59d171139fd781e36f9541f0a4b89cd4ca06486872e6bb80acc684abb6365a82fb077a1079f6b3700453880b7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
