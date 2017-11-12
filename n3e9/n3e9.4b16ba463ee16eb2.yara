
rule n3e9_4b16ba463ee16eb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b16ba463ee16eb2"
     cluster="n3e9.4b16ba463ee16eb2"
     cluster_size="160"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler archsms"
     md5_hashes="['0430c7ac7c17707cb9b9de742543da26','04b0598f184b9adfbfff1e9d94558661','2f73bdf3115231056538b1002bc65cc3']"

   strings:
      $hex_string = { 000102f011030421315105064161a11207718191c122130809b1d1327233b31435b57637e142522383447415f19253935464d456571819627324b44555751626 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
