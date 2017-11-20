
rule m3e9_4c1e3299c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4c1e3299c6620b12"
     cluster="m3e9.4c1e3299c6620b12"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob sality"
     md5_hashes="['05fa22cec17e93478b052585b7131e22','33785fcb15c372faed606f841bb34416','bf8efffe1fb812ea3f52f4332cb5adb7']"

   strings:
      $hex_string = { bee21affadbd790ac7bff31bd838f6c358bbed937cec8603ede5a54efef2994bfd617f040c479ce79acc3023b5d0d54977012a6d082589c0fb6b823650e42e98 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
