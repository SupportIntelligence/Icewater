
rule n3e9_29c615e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c615e9c8800b12"
     cluster="n3e9.29c615e9c8800b12"
     cluster_size="182"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy cuegoe trojandropper"
     md5_hashes="['015eea153ba64cdbeaf49e198cc18ed1','026b15413befbfd65b356ebea0528726','30a74aa5d6abef00eec9596e5abed772']"

   strings:
      $hex_string = { 0052316a318732aa32c432e53207335033993343344e34f234603513364436c9377f3889383d394c39c339d039a53aaf3a4f3b8d3bbf3be73b243ea43e0f3f22 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
