
rule n3e9_1119569dea33db12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1119569dea33db12"
     cluster="n3e9.1119569dea33db12"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler optimuminstaller"
     md5_hashes="['0b57603e4d661bf9e7fb5a8988e8c138','15e7f37691b590c5d7890b9b654f6629','cc3b08364066fb800992b6f884b77050']"

   strings:
      $hex_string = { 9ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3318202333082022f0201013081c930 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
