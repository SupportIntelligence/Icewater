
rule o3f7_4994e848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f7.4994e848c0000b12"
     cluster="o3f7.4994e848c0000b12"
     cluster_size="35"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['009f6c4dc1b3aa412b2d967d5de998cc','0d775c2865cec016bbf841e4d62d30f2','7bbbda89e31a40539ecef6ffaf5f440c']"

   strings:
      $hex_string = { 73254334254231273e596574656e656b2053697a73696e697a2054c3bc726b69796520323031312048c3bc6c7961204176c59f6172262333393bc4b16e204b75 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
