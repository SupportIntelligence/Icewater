
rule m3f7_499c9099c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.499c9099c2200b32"
     cluster="m3f7.499c9099c2200b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['28bf6b4c58ce719295649cfdfd0c220e','381fb4bf395ba3b2fbb8f2bbde02bc52','c9d6764bfad2c81b17aba1ea01fc3e79']"

   strings:
      $hex_string = { 4279496428274174747269627574696f6e3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
