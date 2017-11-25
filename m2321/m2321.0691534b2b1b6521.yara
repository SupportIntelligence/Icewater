
rule m2321_0691534b2b1b6521
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0691534b2b1b6521"
     cluster="m2321.0691534b2b1b6521"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar midie scudy"
     md5_hashes="['0cfadc75f7203c959b94ec0cf63bbe9e','332a1f2bc5461020e02c25e66e299689','61f6ef7f19d8e306946c3ae1eca0f407']"

   strings:
      $hex_string = { 3785aa904d662e0af1dd9b5805d4adac99316b8e5c9e0f23ab873ca53e427b8da6b4be16f603f971fd8c6080020e38119491e53db7d0d9a1bc6a786cc9a8349a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
