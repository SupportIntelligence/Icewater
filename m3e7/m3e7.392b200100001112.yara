
rule m3e7_392b200100001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.392b200100001112"
     cluster="m3e7.392b200100001112"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut graftor shodi"
     md5_hashes="['38b43b45b7b609bf845ff5018024af2e','918484c1c908080dbd48864262fe86d5','dc9095067013ad337e2667cc515e274a']"

   strings:
      $hex_string = { 522957e36bd63455c00d8e4b9408f7446ac7b3e54cd99fe7af108c35f3e9a77f1df5eab25e052337f860e49a1558a84e635967537c11763bdeadf1c250b60341 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
