
rule m2318_699d684cd8bf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.699d684cd8bf4912"
     cluster="m2318.699d684cd8bf4912"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0021c27da84edcd934da62748c9e81f4','2bca12d016227d1eba91684aab898b6c','e27a8d500772da084fb1b13e871f58a0']"

   strings:
      $hex_string = { 34363242363643373041383939424544444541343244463430353932443730434131374536324230464335304437463534303542353133314332383338333336 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
