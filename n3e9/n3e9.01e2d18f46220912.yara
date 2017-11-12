
rule n3e9_01e2d18f46220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.01e2d18f46220912"
     cluster="n3e9.01e2d18f46220912"
     cluster_size="11055"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="urelas zusy gupboot"
     md5_hashes="['0003488e68994435feaebc1c3754f7a5','000f4e1f2f2802c20d6b1557a2ff794c','005ba03196de28a4d94a5de8e199e3bf']"

   strings:
      $hex_string = { 18cd7382c34a66e7595e71ab83577679943c0f1dac50b7930d47386c7c457209d054dff87eda1f9aafbc4ee89d8612aef1dce36804209fa7b687744da84fd777 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
