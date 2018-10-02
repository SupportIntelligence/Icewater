
rule o3f8_492ea5a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.492ea5a1c2000932"
     cluster="o3f8.492ea5a1c2000932"
     cluster_size="514"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp scamapp androidos"
     md5_hashes="['8b5daccc028515bf7838e6ebea3cc31857db1f4e','7db27877af08cb5f0b771f2adf0634cba6585452','02570c150aa5732ee7ff12a07cb25e117e87bcfb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.492ea5a1c2000932"

   strings:
      $hex_string = { 744a656c6c796265616e4d72312e6a6176610010484356696577436f6d706174496d706c0012484542525f5343524950545f535542544147000648494444454e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
