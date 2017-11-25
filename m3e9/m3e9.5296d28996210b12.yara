
rule m3e9_5296d28996210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5296d28996210b12"
     cluster="m3e9.5296d28996210b12"
     cluster_size="287"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi wbna vbkrypt"
     md5_hashes="['0118350921b0cbb73ffc74bb6d62cdf3','05aa7a70091a9667af329e14862b5125','4324ef15cd9232473203b45fd19ebe4e']"

   strings:
      $hex_string = { 682a560000e8df4bfeffff155810400068d0fc4100eb308b4df083e10485c974098d4dc8ff15201040008d55bc528d45c0506a02ff158411400083c40c8d4dac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
