
rule n3e9_6a5e3825535a48f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6a5e3825535a48f2"
     cluster="n3e9.6a5e3825535a48f2"
     cluster_size="47"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="multiplug mplug nbjr"
     md5_hashes="['00f62d101909f3c9c72337c2d879abbe','036671f96b17b0b9fc317ff4d4fa92a5','5caf35dfbe8318729e2f92990d494332']"

   strings:
      $hex_string = { 31be32c432b233b833ac34b23495359b3599369f3636373c37ae38b43804390a3986398c39083a0e3ac53bcb3b453c4b3cda3ce03c723d783d5b3e613e273f2d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
