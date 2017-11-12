
rule k3e9_5297a449c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5297a449c0000b16"
     cluster="k3e9.5297a449c0000b16"
     cluster_size="956"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot upatre generickd"
     md5_hashes="['003d2df658c3a7f4fd9ddfd3a6941e29','00537f85794914f623b541d7efdd0c42','0979d5f8c70038adf61b35bb17c07506']"

   strings:
      $hex_string = { 67654c6973745f4164644d61736b6564005400496d6167654c6973745f44657374726f79005300496d6167654c6973745f43726561746500004d00496d616765 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
