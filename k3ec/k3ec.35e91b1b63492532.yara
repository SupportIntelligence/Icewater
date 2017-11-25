
rule k3ec_35e91b1b63492532
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.35e91b1b63492532"
     cluster="k3ec.35e91b1b63492532"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="resur senna malicious"
     md5_hashes="['8ae2d43799a52b85e8f5b916eee74c93','a7cf8628414414ed8e7c7ac18a23ae7e','df90272d65832fb6a10b9c1fbb7dcf86']"

   strings:
      $hex_string = { 88369636c736cd36e536273756375c379537bc376138683877389a38a038b838f93862397c3985397d3a8c3a9e3ac43ad13adf3aea3afd3a243b333b753b893b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
