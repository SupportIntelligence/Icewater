
rule m3e9_16cb17422a69a657
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16cb17422a69a657"
     cluster="m3e9.16cb17422a69a657"
     cluster_size="878"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup lethic zbot"
     md5_hashes="['0073273ae62c76a9f1035049e6ef3230','00c0599957485b3f6f38414d84fdf226','06c696ae624dc8cbf1af4492ff8cc603']"

   strings:
      $hex_string = { 784f6e000000928c67f5bceb1d1cfd84ebbecb0bcc15b95467b581ef35f920be25fe524fedc6475ea95283e328dde20afe546c40b540d985deac4595c1deb27c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
