
rule o3e9_31329104ea211912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.31329104ea211912"
     cluster="o3e9.31329104ea211912"
     cluster_size="8663"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt eyestye injector"
     md5_hashes="['0006be9fca9df211f9db10c2d1fa034c','0007d2fdc36139d12cac9ac44e44fd1f','01188cf7f6b8d254f3f48b79014e02de']"

   strings:
      $hex_string = { d9000000d5000000d2000000cd000000c9000000c4000000bf000000ba000000b4000000ae000000a8000000a10000009a000000930000008b00000083000000 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
