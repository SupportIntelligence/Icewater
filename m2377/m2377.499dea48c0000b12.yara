
rule m2377_499dea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.499dea48c0000b12"
     cluster="m2377.499dea48c0000b12"
     cluster_size="10"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1013448a6557377e6765bfb96fda1725','2c81842e4d32f16d1cab5b0dcc00b813','f4f13fff99b5f5d59192d5317d6e3939']"

   strings:
      $hex_string = { 30e027478f176fb424ee202eb8f54268cc9fd4cfaa103d9516f1a1fa1f3fd2bae189aecd3198048b515c091db54b8c6082cab89ca088d5f4a94314e3f84c4edb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
