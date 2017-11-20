
rule k3e9_58d918ec6ec10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.58d918ec6ec10b12"
     cluster="k3e9.58d918ec6ec10b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol kazy microfake"
     md5_hashes="['3a5e974a30a23c1aa0bc159191065059','87d0b6555f8993b646448699a99a59c4','f06ec1f5a78217ae87430427d337b9ab']"

   strings:
      $hex_string = { 10722d2b4424103d00dd6d007722ff15782000103b442414751655ff359c320010ffd73bc374d433c05f5e5d5b5959c333c040ebf4558bec81ec68060000536a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
