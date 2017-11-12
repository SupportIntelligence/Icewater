
rule n3e9_2db35c92daf91932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2db35c92daf91932"
     cluster="n3e9.2db35c92daf91932"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['0fa08ae7498a5f781f270f9c3bf520fa','140894e40a254a09bb08f2d37b86816c','d1d0b6e1e4baead885fbb05774ced216']"

   strings:
      $hex_string = { 070707070707070707070707070707070715070c0c0c0c0c0c0c010b0c0c0c0c0c0c06060c0c1a0c0c0c0c07070d0d0d0d0d0d0d0d0d0d0707071a1a07151515 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
