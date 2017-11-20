
rule k3e9_193c69e351b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193c69e351b2f316"
     cluster="k3e9.193c69e351b2f316"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply installcore domaiq"
     md5_hashes="['22347d20ab1bfca8340b36e60f32cda3','35d6b55daf5e4d5f3da96d163e0d9601','fb1aa1f744bee03078e90462b1d0d207']"

   strings:
      $hex_string = { cf78fe72121d0f4f07c8f67b6ca7c67e8a02b44b90d427fa995c050362cbbcf8002b40a9a809db9f2293532a3f3cc94384411c6d823694daec28e63849d669e8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
