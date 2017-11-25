
rule m3e9_611e1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e1cc1cc000b12"
     cluster="m3e9.611e1cc1cc000b12"
     cluster_size="1836"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['00e125210f5910e41902ef3fdf718510','017db11b96bb42e0b746172bd89494b0','063a1621d28fcbba1d74327e12e7b222']"

   strings:
      $hex_string = { 70e58d414da86cd51fee5718b788db136bb58c30d6464b80657495e44475ab319e2af3b051724cc93aac6940b2c34af19366995c075e7610e11e977327da6747 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
