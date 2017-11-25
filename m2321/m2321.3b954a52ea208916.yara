
rule m2321_3b954a52ea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b954a52ea208916"
     cluster="m2321.3b954a52ea208916"
     cluster_size="36"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma blocker"
     md5_hashes="['0375974b5cf2b85dd09fb5cf2a3ff0ef','0d6b3fffa4e91cc33fe762cb581b15a5','584384815b5ca3b51743e25479d3dd62']"

   strings:
      $hex_string = { ff317ee73b472e097979efdf5525d057dd527640e2b667e06ac9b9ad6e873ea55bceb10d5eee924e1df1884a77d37bec5f29b02dd8dc2c7c9b6fc4a1bb17308f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
