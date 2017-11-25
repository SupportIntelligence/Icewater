
rule j3f8_7094d6c3c8000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7094d6c3c8000130"
     cluster="j3f8.7094d6c3c8000130"
     cluster_size="14"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos fyec"
     md5_hashes="['2af3dfe4e52177e825188a861f5904c1','32b30ea99441f740c6a163598823958c','fe669cb1cc19fa22f367d428cfc92fed']"

   strings:
      $hex_string = { 61626c650001620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
