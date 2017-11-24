
rule k3e9_2351cd159d6b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2351cd159d6b0b32"
     cluster="k3e9.2351cd159d6b0b32"
     cluster_size="385"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot graftor delf"
     md5_hashes="['00b535f2142aac1c79fa9efd8b1cbd6d','00fdc77d72b66c34f0eabfec32ae7b96','0ab025086513ae8aac1b26ee014d34b1']"

   strings:
      $hex_string = { 48fc33d552508ec7990604241654240783c40b8a55f788104aff4def0f8574ffff025f5e5e8be560c38d43005359575586c4f8c138b5446a0fbaf98be281c395 }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
