
rule k3f7_13991fa1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.13991fa1c2000b32"
     cluster="k3f7.13991fa1c2000b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery redirector script"
     md5_hashes="['23201897e2bfaedc19a5a5f98fa612b4','4323bc5d42942dc14bedb7502f2f2069','ca10fef9b3fd9d746488d58056d402aa']"

   strings:
      $hex_string = { 6e636c756465732f6a732f6a71756572792e666f726d2e6d696e2e6a733f7665723d332e35312e302d323031342e30362e3230273e3c2f7363726970743e0a3c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
