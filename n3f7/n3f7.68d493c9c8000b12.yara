
rule n3f7_68d493c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.68d493c9c8000b12"
     cluster="n3f7.68d493c9c8000b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0ed2ee7e7c305999d67c570407876779','2a317794eb1bf41804280afae784682f','d3400485517a1d421f43910bc5feff02']"

   strings:
      $hex_string = { 42363643373041383939424544444541343244463430353932443730434131374536324230464335304437463534303542353133314332383338333336333142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
