
rule kfc8_1d1e96e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.1d1e96e9c8800b32"
     cluster="kfc8.1d1e96e9c8800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware andr banker"
     md5_hashes="['648d7528582b8ccb499b0423d7f099a6d2f1f33a','11a717a974f0092cf0def1c80a08ab20e2b24b8c','6936ba0c0c247ec79cab7e100aa3edfd96ee29ab']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.1d1e96e9c8800b32"

   strings:
      $hex_string = { 530009364e3107147abec8ba710e19acdbd0cfd1a41290dacc830c2bce4a58d7cdd27860d9d48264d35f8fcbd6aa242281bd3c1873c6c413bfd8430f65bc7f1a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
