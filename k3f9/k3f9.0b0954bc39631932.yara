
rule k3f9_0b0954bc39631932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.0b0954bc39631932"
     cluster="k3f9.0b0954bc39631932"
     cluster_size="1301"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok pazetus email"
     md5_hashes="['007f650b1852e2e61044e1757fc43e42','00b36f8a83c71ad6f50b1df56e8e65b2','059250b80788c702ff830b7dac045cf6']"

   strings:
      $hex_string = { 537c50c16a31227d3b419ad9d5a7975ce401559d02b803e25af7f6723e14bdfe686c4064d15bee2c9d26f52519a658df009e6e2f700cb02e562474288df0b6e9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
