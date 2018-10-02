
rule o26bb_36cb2304ea608b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.36cb2304ea608b12"
     cluster="o26bb.36cb2304ea608b12"
     cluster_size="83"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dangerousobject dangeroussig eksktak"
     md5_hashes="['af2298b33277af2f4688838974b7e4d2611a9e45','72bb9660a934e076f2e43e7f5b33a085718d1bf2','c803bd1b95baa7021038864a06d2a68afc8b07c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.36cb2304ea608b12"

   strings:
      $hex_string = { fa0b0b0b9d03030313a600000000a500000000020101010a08080876101010ee81111111ff07121212ff141414ff151515ff161616ff181818ff191919ff1b1b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
