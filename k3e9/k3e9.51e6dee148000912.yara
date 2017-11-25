
rule k3e9_51e6dee148000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51e6dee148000912"
     cluster="k3e9.51e6dee148000912"
     cluster_size="15004"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy upatre malicious"
     md5_hashes="['00018e44225da115e3cb10917cb18238','0006c07d7cf8fe814f8b3a88b6d1fb8c','00a5fdf670f60162f41cc920a1d000c0']"

   strings:
      $hex_string = { 687c21000224410f8d52f7153e1cf8ff550f0175c0e987fafffb834df0858b90c08b4138fd75f803bf840f83040bb744066bc1288b248d8b8b84f9cbfefcff8a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
