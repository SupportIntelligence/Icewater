
rule k3e9_053558569ebb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.053558569ebb1932"
     cluster="k3e9.053558569ebb1932"
     cluster_size="18"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['0609ce7050987c34b42a7bc0ea126d5f','12699e1278750410cdf9cbe17e6519d3','ee881f2a9eed61b2a82307a00f238c55']"

   strings:
      $hex_string = { 36ffd78906eb323c097c0c3c0a7e273c0d74233c20741f57ff154c5100013bf88906730a8a07478803433b3e72f68b3e8a0784c075d180230033c05f5e5bc9c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
