
rule m3f7_4e9b008cca200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4e9b008cca200932"
     cluster="m3f7.4e9b008cca200932"
     cluster_size="12"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['068a77f0de9f0ea83f1fe586c74a5a11','269596a21f67b3a1ae5807b16105f4c1','b4aa6f5e850706c6c877c9b81ed200bc']"

   strings:
      $hex_string = { 34363242363643373041383939424544444541343244463430353932443730434131374536324230464335304437463534303542353133314332383338333336 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
